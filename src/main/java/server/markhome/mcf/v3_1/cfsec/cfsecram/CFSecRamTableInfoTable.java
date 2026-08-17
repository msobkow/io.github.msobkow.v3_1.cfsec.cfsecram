
// Description: Java 25 in-memory RAM DbIO implementation for TableInfo.

/*
 *	server.markhome.mcf.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	These files are part of Mark's Code Fractal CFSec.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *	
 */

package server.markhome.mcf.v3_1.cfsec.cfsecram;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.time.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;

import server.markhome.mcf.v3_1.cfsec.cfsec.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.buff.*;
import server.markhome.mcf.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamTableInfoTable in-memory RAM DbIO implementation
 *	for TableInfo.
 */
public class CFSecRamTableInfoTable
	implements ICFSecTableInfoTable
{
	private ICFSecSchema schema;
	private Map< Integer,
				CFSecBuffTableInfo > dictByPKey
		= new HashMap< Integer,
				CFSecBuffTableInfo >();
	private Map< CFSecBuffTableInfoByTableNameIdxKey,
			CFSecBuffTableInfo > dictByTableNameIdx
		= new HashMap< CFSecBuffTableInfoByTableNameIdxKey,
			CFSecBuffTableInfo >();
	private Map< CFSecBuffTableInfoBySuperNameIdxKey,
				Map< Integer,
					CFSecBuffTableInfo >> dictBySuperNameIdx
		= new HashMap< CFSecBuffTableInfoBySuperNameIdxKey,
				Map< Integer,
					CFSecBuffTableInfo >>();
	private Map< CFSecBuffTableInfoBySchemaNameIdxKey,
				Map< Integer,
					CFSecBuffTableInfo >> dictBySchemaNameIdx
		= new HashMap< CFSecBuffTableInfoBySchemaNameIdxKey,
				Map< Integer,
					CFSecBuffTableInfo >>();
	private Map< CFSecBuffTableInfoBySchemaBkCodeIdxKey,
			CFSecBuffTableInfo > dictBySchemaBkCodeIdx
		= new HashMap< CFSecBuffTableInfoBySchemaBkCodeIdxKey,
			CFSecBuffTableInfo >();
	private Map< CFSecBuffTableInfoBySchemaRTCodeIdxKey,
			CFSecBuffTableInfo > dictBySchemaRTCodeIdx
		= new HashMap< CFSecBuffTableInfoBySchemaRTCodeIdxKey,
			CFSecBuffTableInfo >();

	public CFSecRamTableInfoTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffTableInfo ensureRec(ICFSecTableInfo rec) {
		return (((CFSecBuffTableInfoFactoryService)(schema.getCFSecBuffFactory().getFactoryTableInfo())).ensureRec(rec));
	}

	@Override
	public ICFSecTableInfo createTableInfo( ICFSecAuthorization Authorization,
		ICFSecTableInfo iBuff )
	{
		final String S_ProcName = "createTableInfo";
		
		CFSecBuffTableInfo Buff = (CFSecBuffTableInfo)ensureRec(iBuff);
		Integer pkey;
		pkey = schema.nextTableInfoIdGen();
		Buff.setRequiredTableInfoId( pkey );
		CFSecBuffTableInfoByTableNameIdxKey keyTableNameIdx = (CFSecBuffTableInfoByTableNameIdxKey)schema.getCFSecBuffFactory().getFactoryTableInfo().newByTableNameIdxKey();
		keyTableNameIdx.setRequiredTableName( Buff.getRequiredTableName() );

		CFSecBuffTableInfoBySuperNameIdxKey keySuperNameIdx = (CFSecBuffTableInfoBySuperNameIdxKey)schema.getCFSecBuffFactory().getFactoryTableInfo().newBySuperNameIdxKey();
		keySuperNameIdx.setOptionalSuperName( Buff.getOptionalSuperName() );

		CFSecBuffTableInfoBySchemaNameIdxKey keySchemaNameIdx = (CFSecBuffTableInfoBySchemaNameIdxKey)schema.getCFSecBuffFactory().getFactoryTableInfo().newBySchemaNameIdxKey();
		keySchemaNameIdx.setRequiredSchemaName( Buff.getRequiredSchemaName() );

		CFSecBuffTableInfoBySchemaBkCodeIdxKey keySchemaBkCodeIdx = (CFSecBuffTableInfoBySchemaBkCodeIdxKey)schema.getCFSecBuffFactory().getFactoryTableInfo().newBySchemaBkCodeIdxKey();
		keySchemaBkCodeIdx.setRequiredSchemaName( Buff.getRequiredSchemaName() );
		keySchemaBkCodeIdx.setRequiredBackingClassCode( Buff.getRequiredBackingClassCode() );

		CFSecBuffTableInfoBySchemaRTCodeIdxKey keySchemaRTCodeIdx = (CFSecBuffTableInfoBySchemaRTCodeIdxKey)schema.getCFSecBuffFactory().getFactoryTableInfo().newBySchemaRTCodeIdxKey();
		keySchemaRTCodeIdx.setRequiredRuntimeClassCode( Buff.getRequiredRuntimeClassCode() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByTableNameIdx.containsKey( keyTableNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"TableInfoTableNameIdx",
				"TableInfoTableNameIdx",
				keyTableNameIdx );
		}

		if( dictBySchemaBkCodeIdx.containsKey( keySchemaBkCodeIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"TableInfoSchemaBkCodeIdx",
				"TableInfoSchemaBkCodeIdx",
				keySchemaBkCodeIdx );
		}

		if( dictBySchemaRTCodeIdx.containsKey( keySchemaRTCodeIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"TableInfoSchemaRTCodeIdx",
				"TableInfoSchemaRTCodeIdx",
				keySchemaRTCodeIdx );
		}

		// Validate foreign keys

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		dictByTableNameIdx.put( keyTableNameIdx, Buff );

		Map< Integer, CFSecBuffTableInfo > subdictSuperNameIdx;
		if( dictBySuperNameIdx.containsKey( keySuperNameIdx ) ) {
			subdictSuperNameIdx = dictBySuperNameIdx.get( keySuperNameIdx );
		}
		else {
			subdictSuperNameIdx = new HashMap< Integer, CFSecBuffTableInfo >();
			dictBySuperNameIdx.put( keySuperNameIdx, subdictSuperNameIdx );
		}
		subdictSuperNameIdx.put( pkey, Buff );

		Map< Integer, CFSecBuffTableInfo > subdictSchemaNameIdx;
		if( dictBySchemaNameIdx.containsKey( keySchemaNameIdx ) ) {
			subdictSchemaNameIdx = dictBySchemaNameIdx.get( keySchemaNameIdx );
		}
		else {
			subdictSchemaNameIdx = new HashMap< Integer, CFSecBuffTableInfo >();
			dictBySchemaNameIdx.put( keySchemaNameIdx, subdictSchemaNameIdx );
		}
		subdictSchemaNameIdx.put( pkey, Buff );

		dictBySchemaBkCodeIdx.put( keySchemaBkCodeIdx, Buff );

		dictBySchemaRTCodeIdx.put( keySchemaRTCodeIdx, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecTableInfo.CLASS_CODE) {
				CFSecBuffTableInfo retbuff = ((CFSecBuffTableInfo)(schema.getCFSecBuffFactory().getFactoryTableInfo().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecTableInfo readDerived( ICFSecAuthorization Authorization,
		Integer PKey )
	{
		final String S_ProcName = "CFSecRamTableInfo.readDerived";
		ICFSecTableInfo buff;
		if( PKey == null ) {
			return( null );
		}
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecTableInfo lockDerived( ICFSecAuthorization Authorization,
		Integer PKey )
	{
		final String S_ProcName = "CFSecRamTableInfo.lockDerived";
		ICFSecTableInfo buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecTableInfo[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamTableInfo.readAllDerived";
		ICFSecTableInfo[] retList = new ICFSecTableInfo[ dictByPKey.values().size() ];
		Iterator< CFSecBuffTableInfo > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	@Override
	public ICFSecTableInfo readDerivedByTableNameIdx( ICFSecAuthorization Authorization,
		String TableName )
	{
		final String S_ProcName = "CFSecRamTableInfo.readDerivedByTableNameIdx";
		CFSecBuffTableInfoByTableNameIdxKey key = (CFSecBuffTableInfoByTableNameIdxKey)schema.getCFSecBuffFactory().getFactoryTableInfo().newByTableNameIdxKey();

		key.setRequiredTableName( TableName );
		ICFSecTableInfo buff;
		if( dictByTableNameIdx.containsKey( key ) ) {
			buff = dictByTableNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecTableInfo[] readDerivedBySuperNameIdx( ICFSecAuthorization Authorization,
		String SuperName )
	{
		final String S_ProcName = "CFSecRamTableInfo.readDerivedBySuperNameIdx";
		CFSecBuffTableInfoBySuperNameIdxKey key = (CFSecBuffTableInfoBySuperNameIdxKey)schema.getCFSecBuffFactory().getFactoryTableInfo().newBySuperNameIdxKey();

		key.setOptionalSuperName( SuperName );
		ICFSecTableInfo[] recArray;
		if( dictBySuperNameIdx.containsKey( key ) ) {
			Map< Integer, CFSecBuffTableInfo > subdictSuperNameIdx
				= dictBySuperNameIdx.get( key );
			recArray = new ICFSecTableInfo[ subdictSuperNameIdx.size() ];
			Iterator< CFSecBuffTableInfo > iter = subdictSuperNameIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< Integer, CFSecBuffTableInfo > subdictSuperNameIdx
				= new HashMap< Integer, CFSecBuffTableInfo >();
			dictBySuperNameIdx.put( key, subdictSuperNameIdx );
			recArray = new ICFSecTableInfo[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecTableInfo[] readDerivedBySchemaNameIdx( ICFSecAuthorization Authorization,
		String SchemaName )
	{
		final String S_ProcName = "CFSecRamTableInfo.readDerivedBySchemaNameIdx";
		CFSecBuffTableInfoBySchemaNameIdxKey key = (CFSecBuffTableInfoBySchemaNameIdxKey)schema.getCFSecBuffFactory().getFactoryTableInfo().newBySchemaNameIdxKey();

		key.setRequiredSchemaName( SchemaName );
		ICFSecTableInfo[] recArray;
		if( dictBySchemaNameIdx.containsKey( key ) ) {
			Map< Integer, CFSecBuffTableInfo > subdictSchemaNameIdx
				= dictBySchemaNameIdx.get( key );
			recArray = new ICFSecTableInfo[ subdictSchemaNameIdx.size() ];
			Iterator< CFSecBuffTableInfo > iter = subdictSchemaNameIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< Integer, CFSecBuffTableInfo > subdictSchemaNameIdx
				= new HashMap< Integer, CFSecBuffTableInfo >();
			dictBySchemaNameIdx.put( key, subdictSchemaNameIdx );
			recArray = new ICFSecTableInfo[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecTableInfo readDerivedBySchemaBkCodeIdx( ICFSecAuthorization Authorization,
		String SchemaName,
		int BackingClassCode )
	{
		final String S_ProcName = "CFSecRamTableInfo.readDerivedBySchemaBkCodeIdx";
		CFSecBuffTableInfoBySchemaBkCodeIdxKey key = (CFSecBuffTableInfoBySchemaBkCodeIdxKey)schema.getCFSecBuffFactory().getFactoryTableInfo().newBySchemaBkCodeIdxKey();

		key.setRequiredSchemaName( SchemaName );
		key.setRequiredBackingClassCode( BackingClassCode );
		ICFSecTableInfo buff;
		if( dictBySchemaBkCodeIdx.containsKey( key ) ) {
			buff = dictBySchemaBkCodeIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecTableInfo readDerivedBySchemaRTCodeIdx( ICFSecAuthorization Authorization,
		int RuntimeClassCode )
	{
		final String S_ProcName = "CFSecRamTableInfo.readDerivedBySchemaRTCodeIdx";
		CFSecBuffTableInfoBySchemaRTCodeIdxKey key = (CFSecBuffTableInfoBySchemaRTCodeIdxKey)schema.getCFSecBuffFactory().getFactoryTableInfo().newBySchemaRTCodeIdxKey();

		key.setRequiredRuntimeClassCode( RuntimeClassCode );
		ICFSecTableInfo buff;
		if( dictBySchemaRTCodeIdx.containsKey( key ) ) {
			buff = dictBySchemaRTCodeIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecTableInfo readDerivedByIdIdx( ICFSecAuthorization Authorization,
		int TableInfoId )
	{
		final String S_ProcName = "CFSecRamTableInfo.readDerivedByIdIdx() ";
		ICFSecTableInfo buff;
		if( dictByPKey.containsKey( TableInfoId ) ) {
			buff = dictByPKey.get( TableInfoId );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecTableInfo readRec( ICFSecAuthorization Authorization,
		Integer PKey )
	{
		final String S_ProcName = "CFSecRamTableInfo.readRec";
		ICFSecTableInfo buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecTableInfo.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecTableInfo lockRec( ICFSecAuthorization Authorization,
		Integer PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecTableInfo buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecTableInfo.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecTableInfo[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamTableInfo.readAllRec";
		ICFSecTableInfo buff;
		ArrayList<ICFSecTableInfo> filteredList = new ArrayList<ICFSecTableInfo>();
		ICFSecTableInfo[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecTableInfo.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecTableInfo[0] ) );
	}

	@Override
	public ICFSecTableInfo readRecByIdIdx( ICFSecAuthorization Authorization,
		int TableInfoId )
	{
		final String S_ProcName = "CFSecRamTableInfo.readRecByIdIdx() ";
		ICFSecTableInfo buff = readDerivedByIdIdx( Authorization,
			TableInfoId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecTableInfo.CLASS_CODE ) ) {
			return( (ICFSecTableInfo)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecTableInfo readRecByTableNameIdx( ICFSecAuthorization Authorization,
		String TableName )
	{
		final String S_ProcName = "CFSecRamTableInfo.readRecByTableNameIdx() ";
		ICFSecTableInfo buff = readDerivedByTableNameIdx( Authorization,
			TableName );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecTableInfo.CLASS_CODE ) ) {
			return( (ICFSecTableInfo)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecTableInfo[] readRecBySuperNameIdx( ICFSecAuthorization Authorization,
		String SuperName )
	{
		final String S_ProcName = "CFSecRamTableInfo.readRecBySuperNameIdx() ";
		ICFSecTableInfo buff;
		ArrayList<ICFSecTableInfo> filteredList = new ArrayList<ICFSecTableInfo>();
		ICFSecTableInfo[] buffList = readDerivedBySuperNameIdx( Authorization,
			SuperName );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecTableInfo.CLASS_CODE ) ) {
				filteredList.add( (ICFSecTableInfo)buff );
			}
		}
		return( filteredList.toArray( new ICFSecTableInfo[0] ) );
	}

	@Override
	public ICFSecTableInfo[] readRecBySchemaNameIdx( ICFSecAuthorization Authorization,
		String SchemaName )
	{
		final String S_ProcName = "CFSecRamTableInfo.readRecBySchemaNameIdx() ";
		ICFSecTableInfo buff;
		ArrayList<ICFSecTableInfo> filteredList = new ArrayList<ICFSecTableInfo>();
		ICFSecTableInfo[] buffList = readDerivedBySchemaNameIdx( Authorization,
			SchemaName );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecTableInfo.CLASS_CODE ) ) {
				filteredList.add( (ICFSecTableInfo)buff );
			}
		}
		return( filteredList.toArray( new ICFSecTableInfo[0] ) );
	}

	@Override
	public ICFSecTableInfo readRecBySchemaBkCodeIdx( ICFSecAuthorization Authorization,
		String SchemaName,
		int BackingClassCode )
	{
		final String S_ProcName = "CFSecRamTableInfo.readRecBySchemaBkCodeIdx() ";
		ICFSecTableInfo buff = readDerivedBySchemaBkCodeIdx( Authorization,
			SchemaName,
			BackingClassCode );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecTableInfo.CLASS_CODE ) ) {
			return( (ICFSecTableInfo)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecTableInfo readRecBySchemaRTCodeIdx( ICFSecAuthorization Authorization,
		int RuntimeClassCode )
	{
		final String S_ProcName = "CFSecRamTableInfo.readRecBySchemaRTCodeIdx() ";
		ICFSecTableInfo buff = readDerivedBySchemaRTCodeIdx( Authorization,
			RuntimeClassCode );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecTableInfo.CLASS_CODE ) ) {
			return( (ICFSecTableInfo)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecTableInfo updateTableInfo( ICFSecAuthorization Authorization,
		ICFSecTableInfo iBuff )
	{
		CFSecBuffTableInfo Buff = (CFSecBuffTableInfo)ensureRec(iBuff);
		Integer pkey = (Integer)Buff.getPKey();
		CFSecBuffTableInfo existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateTableInfo",
				"Existing record not found",
				"Existing record not found",
				"TableInfo",
				"TableInfo",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateTableInfo",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffTableInfoByTableNameIdxKey existingKeyTableNameIdx = (CFSecBuffTableInfoByTableNameIdxKey)schema.getCFSecBuffFactory().getFactoryTableInfo().newByTableNameIdxKey();
		existingKeyTableNameIdx.setRequiredTableName( existing.getRequiredTableName() );

		CFSecBuffTableInfoByTableNameIdxKey newKeyTableNameIdx = (CFSecBuffTableInfoByTableNameIdxKey)schema.getCFSecBuffFactory().getFactoryTableInfo().newByTableNameIdxKey();
		newKeyTableNameIdx.setRequiredTableName( Buff.getRequiredTableName() );

		CFSecBuffTableInfoBySuperNameIdxKey existingKeySuperNameIdx = (CFSecBuffTableInfoBySuperNameIdxKey)schema.getCFSecBuffFactory().getFactoryTableInfo().newBySuperNameIdxKey();
		existingKeySuperNameIdx.setOptionalSuperName( existing.getOptionalSuperName() );

		CFSecBuffTableInfoBySuperNameIdxKey newKeySuperNameIdx = (CFSecBuffTableInfoBySuperNameIdxKey)schema.getCFSecBuffFactory().getFactoryTableInfo().newBySuperNameIdxKey();
		newKeySuperNameIdx.setOptionalSuperName( Buff.getOptionalSuperName() );

		CFSecBuffTableInfoBySchemaNameIdxKey existingKeySchemaNameIdx = (CFSecBuffTableInfoBySchemaNameIdxKey)schema.getCFSecBuffFactory().getFactoryTableInfo().newBySchemaNameIdxKey();
		existingKeySchemaNameIdx.setRequiredSchemaName( existing.getRequiredSchemaName() );

		CFSecBuffTableInfoBySchemaNameIdxKey newKeySchemaNameIdx = (CFSecBuffTableInfoBySchemaNameIdxKey)schema.getCFSecBuffFactory().getFactoryTableInfo().newBySchemaNameIdxKey();
		newKeySchemaNameIdx.setRequiredSchemaName( Buff.getRequiredSchemaName() );

		CFSecBuffTableInfoBySchemaBkCodeIdxKey existingKeySchemaBkCodeIdx = (CFSecBuffTableInfoBySchemaBkCodeIdxKey)schema.getCFSecBuffFactory().getFactoryTableInfo().newBySchemaBkCodeIdxKey();
		existingKeySchemaBkCodeIdx.setRequiredSchemaName( existing.getRequiredSchemaName() );
		existingKeySchemaBkCodeIdx.setRequiredBackingClassCode( existing.getRequiredBackingClassCode() );

		CFSecBuffTableInfoBySchemaBkCodeIdxKey newKeySchemaBkCodeIdx = (CFSecBuffTableInfoBySchemaBkCodeIdxKey)schema.getCFSecBuffFactory().getFactoryTableInfo().newBySchemaBkCodeIdxKey();
		newKeySchemaBkCodeIdx.setRequiredSchemaName( Buff.getRequiredSchemaName() );
		newKeySchemaBkCodeIdx.setRequiredBackingClassCode( Buff.getRequiredBackingClassCode() );

		CFSecBuffTableInfoBySchemaRTCodeIdxKey existingKeySchemaRTCodeIdx = (CFSecBuffTableInfoBySchemaRTCodeIdxKey)schema.getCFSecBuffFactory().getFactoryTableInfo().newBySchemaRTCodeIdxKey();
		existingKeySchemaRTCodeIdx.setRequiredRuntimeClassCode( existing.getRequiredRuntimeClassCode() );

		CFSecBuffTableInfoBySchemaRTCodeIdxKey newKeySchemaRTCodeIdx = (CFSecBuffTableInfoBySchemaRTCodeIdxKey)schema.getCFSecBuffFactory().getFactoryTableInfo().newBySchemaRTCodeIdxKey();
		newKeySchemaRTCodeIdx.setRequiredRuntimeClassCode( Buff.getRequiredRuntimeClassCode() );

		// Check unique indexes

		if( ! existingKeyTableNameIdx.equals( newKeyTableNameIdx ) ) {
			if( dictByTableNameIdx.containsKey( newKeyTableNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateTableInfo",
					"TableInfoTableNameIdx",
					"TableInfoTableNameIdx",
					newKeyTableNameIdx );
			}
		}

		if( ! existingKeySchemaBkCodeIdx.equals( newKeySchemaBkCodeIdx ) ) {
			if( dictBySchemaBkCodeIdx.containsKey( newKeySchemaBkCodeIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateTableInfo",
					"TableInfoSchemaBkCodeIdx",
					"TableInfoSchemaBkCodeIdx",
					newKeySchemaBkCodeIdx );
			}
		}

		if( ! existingKeySchemaRTCodeIdx.equals( newKeySchemaRTCodeIdx ) ) {
			if( dictBySchemaRTCodeIdx.containsKey( newKeySchemaRTCodeIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateTableInfo",
					"TableInfoSchemaRTCodeIdx",
					"TableInfoSchemaRTCodeIdx",
					newKeySchemaRTCodeIdx );
			}
		}

		// Validate foreign keys

		// Update is valid

		Map< Integer, CFSecBuffTableInfo > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		dictByTableNameIdx.remove( existingKeyTableNameIdx );
		dictByTableNameIdx.put( newKeyTableNameIdx, Buff );

		subdict = dictBySuperNameIdx.get( existingKeySuperNameIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictBySuperNameIdx.containsKey( newKeySuperNameIdx ) ) {
			subdict = dictBySuperNameIdx.get( newKeySuperNameIdx );
		}
		else {
			subdict = new HashMap< Integer, CFSecBuffTableInfo >();
			dictBySuperNameIdx.put( newKeySuperNameIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictBySchemaNameIdx.get( existingKeySchemaNameIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictBySchemaNameIdx.containsKey( newKeySchemaNameIdx ) ) {
			subdict = dictBySchemaNameIdx.get( newKeySchemaNameIdx );
		}
		else {
			subdict = new HashMap< Integer, CFSecBuffTableInfo >();
			dictBySchemaNameIdx.put( newKeySchemaNameIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictBySchemaBkCodeIdx.remove( existingKeySchemaBkCodeIdx );
		dictBySchemaBkCodeIdx.put( newKeySchemaBkCodeIdx, Buff );

		dictBySchemaRTCodeIdx.remove( existingKeySchemaRTCodeIdx );
		dictBySchemaRTCodeIdx.put( newKeySchemaRTCodeIdx, Buff );

		return(Buff);
	}

	@Override
	public void deleteTableInfo( ICFSecAuthorization Authorization,
		ICFSecTableInfo iBuff )
	{
		final String S_ProcName = "CFSecRamTableInfoTable.deleteTableInfo() ";
		CFSecBuffTableInfo Buff = (CFSecBuffTableInfo)ensureRec(iBuff);
		int classCode;
		Integer pkey = (Integer)(Buff.getPKey());
		CFSecBuffTableInfo existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteTableInfo",
				pkey );
		}
		// Short circuit self-referential code to prevent stack overflows
		Object arrCheckTableInfoSubRefs[] = schema.getTableTableInfo().readDerivedBySuperNameIdx( Authorization,
						existing.getRequiredTableName() );
		if( arrCheckTableInfoSubRefs.length > 0 ) {
			schema.getTableTableInfo().deleteTableInfoBySuperNameIdx( Authorization,
						existing.getRequiredTableName() );
		}
		CFSecBuffTableInfoByTableNameIdxKey keyTableNameIdx = (CFSecBuffTableInfoByTableNameIdxKey)schema.getCFSecBuffFactory().getFactoryTableInfo().newByTableNameIdxKey();
		keyTableNameIdx.setRequiredTableName( existing.getRequiredTableName() );

		CFSecBuffTableInfoBySuperNameIdxKey keySuperNameIdx = (CFSecBuffTableInfoBySuperNameIdxKey)schema.getCFSecBuffFactory().getFactoryTableInfo().newBySuperNameIdxKey();
		keySuperNameIdx.setOptionalSuperName( existing.getOptionalSuperName() );

		CFSecBuffTableInfoBySchemaNameIdxKey keySchemaNameIdx = (CFSecBuffTableInfoBySchemaNameIdxKey)schema.getCFSecBuffFactory().getFactoryTableInfo().newBySchemaNameIdxKey();
		keySchemaNameIdx.setRequiredSchemaName( existing.getRequiredSchemaName() );

		CFSecBuffTableInfoBySchemaBkCodeIdxKey keySchemaBkCodeIdx = (CFSecBuffTableInfoBySchemaBkCodeIdxKey)schema.getCFSecBuffFactory().getFactoryTableInfo().newBySchemaBkCodeIdxKey();
		keySchemaBkCodeIdx.setRequiredSchemaName( existing.getRequiredSchemaName() );
		keySchemaBkCodeIdx.setRequiredBackingClassCode( existing.getRequiredBackingClassCode() );

		CFSecBuffTableInfoBySchemaRTCodeIdxKey keySchemaRTCodeIdx = (CFSecBuffTableInfoBySchemaRTCodeIdxKey)schema.getCFSecBuffFactory().getFactoryTableInfo().newBySchemaRTCodeIdxKey();
		keySchemaRTCodeIdx.setRequiredRuntimeClassCode( existing.getRequiredRuntimeClassCode() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< Integer, CFSecBuffTableInfo > subdict;

		dictByPKey.remove( pkey );

		dictByTableNameIdx.remove( keyTableNameIdx );

		subdict = dictBySuperNameIdx.get( keySuperNameIdx );
		subdict.remove( pkey );

		subdict = dictBySchemaNameIdx.get( keySchemaNameIdx );
		subdict.remove( pkey );

		dictBySchemaBkCodeIdx.remove( keySchemaBkCodeIdx );

		dictBySchemaRTCodeIdx.remove( keySchemaRTCodeIdx );

	}
	@Override
	public void deleteTableInfoByIdIdx( ICFSecAuthorization Authorization,
		Integer argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffTableInfo cur;
		LinkedList<CFSecBuffTableInfo> matchSet = new LinkedList<CFSecBuffTableInfo>();
		Iterator<CFSecBuffTableInfo> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffTableInfo> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffTableInfo)(schema.getTableTableInfo().readDerivedByIdIdx( Authorization,
				cur.getRequiredTableInfoId() ));
			deleteTableInfo( Authorization, cur );
		}
	}

	@Override
	public void deleteTableInfoByTableNameIdx( ICFSecAuthorization Authorization,
		String argTableName )
	{
		CFSecBuffTableInfoByTableNameIdxKey key = (CFSecBuffTableInfoByTableNameIdxKey)schema.getCFSecBuffFactory().getFactoryTableInfo().newByTableNameIdxKey();
		key.setRequiredTableName( argTableName );
		deleteTableInfoByTableNameIdx( Authorization, key );
	}

	@Override
	public void deleteTableInfoByTableNameIdx( ICFSecAuthorization Authorization,
		ICFSecTableInfoByTableNameIdxKey argKey )
	{
		CFSecBuffTableInfo cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffTableInfo> matchSet = new LinkedList<CFSecBuffTableInfo>();
		Iterator<CFSecBuffTableInfo> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffTableInfo> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffTableInfo)(schema.getTableTableInfo().readDerivedByIdIdx( Authorization,
				cur.getRequiredTableInfoId() ));
			deleteTableInfo( Authorization, cur );
		}
	}

	@Override
	public void deleteTableInfoBySuperNameIdx( ICFSecAuthorization Authorization,
		String argSuperName )
	{
		CFSecBuffTableInfoBySuperNameIdxKey key = (CFSecBuffTableInfoBySuperNameIdxKey)schema.getCFSecBuffFactory().getFactoryTableInfo().newBySuperNameIdxKey();
		key.setOptionalSuperName( argSuperName );
		deleteTableInfoBySuperNameIdx( Authorization, key );
	}

	@Override
	public void deleteTableInfoBySuperNameIdx( ICFSecAuthorization Authorization,
		ICFSecTableInfoBySuperNameIdxKey argKey )
	{
		CFSecBuffTableInfo cur;
		boolean anyNotNull = false;
		if( argKey.getOptionalSuperName() != null ) {
			anyNotNull = true;
		}
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffTableInfo> matchSet = new LinkedList<CFSecBuffTableInfo>();
		Iterator<CFSecBuffTableInfo> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffTableInfo> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffTableInfo)(schema.getTableTableInfo().readDerivedByIdIdx( Authorization,
				cur.getRequiredTableInfoId() ));
			deleteTableInfo( Authorization, cur );
		}
	}

	@Override
	public void deleteTableInfoBySchemaNameIdx( ICFSecAuthorization Authorization,
		String argSchemaName )
	{
		CFSecBuffTableInfoBySchemaNameIdxKey key = (CFSecBuffTableInfoBySchemaNameIdxKey)schema.getCFSecBuffFactory().getFactoryTableInfo().newBySchemaNameIdxKey();
		key.setRequiredSchemaName( argSchemaName );
		deleteTableInfoBySchemaNameIdx( Authorization, key );
	}

	@Override
	public void deleteTableInfoBySchemaNameIdx( ICFSecAuthorization Authorization,
		ICFSecTableInfoBySchemaNameIdxKey argKey )
	{
		CFSecBuffTableInfo cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffTableInfo> matchSet = new LinkedList<CFSecBuffTableInfo>();
		Iterator<CFSecBuffTableInfo> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffTableInfo> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffTableInfo)(schema.getTableTableInfo().readDerivedByIdIdx( Authorization,
				cur.getRequiredTableInfoId() ));
			deleteTableInfo( Authorization, cur );
		}
	}

	@Override
	public void deleteTableInfoBySchemaBkCodeIdx( ICFSecAuthorization Authorization,
		String argSchemaName,
		int argBackingClassCode )
	{
		CFSecBuffTableInfoBySchemaBkCodeIdxKey key = (CFSecBuffTableInfoBySchemaBkCodeIdxKey)schema.getCFSecBuffFactory().getFactoryTableInfo().newBySchemaBkCodeIdxKey();
		key.setRequiredSchemaName( argSchemaName );
		key.setRequiredBackingClassCode( argBackingClassCode );
		deleteTableInfoBySchemaBkCodeIdx( Authorization, key );
	}

	@Override
	public void deleteTableInfoBySchemaBkCodeIdx( ICFSecAuthorization Authorization,
		ICFSecTableInfoBySchemaBkCodeIdxKey argKey )
	{
		CFSecBuffTableInfo cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffTableInfo> matchSet = new LinkedList<CFSecBuffTableInfo>();
		Iterator<CFSecBuffTableInfo> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffTableInfo> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffTableInfo)(schema.getTableTableInfo().readDerivedByIdIdx( Authorization,
				cur.getRequiredTableInfoId() ));
			deleteTableInfo( Authorization, cur );
		}
	}

	@Override
	public void deleteTableInfoBySchemaRTCodeIdx( ICFSecAuthorization Authorization,
		int argRuntimeClassCode )
	{
		CFSecBuffTableInfoBySchemaRTCodeIdxKey key = (CFSecBuffTableInfoBySchemaRTCodeIdxKey)schema.getCFSecBuffFactory().getFactoryTableInfo().newBySchemaRTCodeIdxKey();
		key.setRequiredRuntimeClassCode( argRuntimeClassCode );
		deleteTableInfoBySchemaRTCodeIdx( Authorization, key );
	}

	@Override
	public void deleteTableInfoBySchemaRTCodeIdx( ICFSecAuthorization Authorization,
		ICFSecTableInfoBySchemaRTCodeIdxKey argKey )
	{
		CFSecBuffTableInfo cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffTableInfo> matchSet = new LinkedList<CFSecBuffTableInfo>();
		Iterator<CFSecBuffTableInfo> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffTableInfo> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffTableInfo)(schema.getTableTableInfo().readDerivedByIdIdx( Authorization,
				cur.getRequiredTableInfoId() ));
			deleteTableInfo( Authorization, cur );
		}
	}
}


// Description: Java 25 in-memory RAM DbIO implementation for SecSysGrpInc.

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
import server.markhome.mcf.v3_1.cflib.keyhash.*;

import server.markhome.mcf.v3_1.cfsec.cfsec.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.buff.*;
import server.markhome.mcf.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamSecSysGrpIncTable in-memory RAM DbIO implementation
 *	for SecSysGrpInc.
 */
public class CFSecRamSecSysGrpIncTable
	implements ICFSecSecSysGrpIncTable
{
	private ICFSecSchema schema;
	private Map< ICFSecSecSysGrpIncPKey,
				CFSecBuffSecSysGrpInc > dictByPKey
		= new HashMap< ICFSecSecSysGrpIncPKey,
				CFSecBuffSecSysGrpInc >();
	private Map< CFSecBuffSecSysGrpIncBySysGrpIdxKey,
				Map< CFSecBuffSecSysGrpIncPKey,
					CFSecBuffSecSysGrpInc >> dictBySysGrpIdx
		= new HashMap< CFSecBuffSecSysGrpIncBySysGrpIdxKey,
				Map< CFSecBuffSecSysGrpIncPKey,
					CFSecBuffSecSysGrpInc >>();
	private Map< CFSecBuffSecSysGrpIncByNameIdxKey,
				Map< CFSecBuffSecSysGrpIncPKey,
					CFSecBuffSecSysGrpInc >> dictByNameIdx
		= new HashMap< CFSecBuffSecSysGrpIncByNameIdxKey,
				Map< CFSecBuffSecSysGrpIncPKey,
					CFSecBuffSecSysGrpInc >>();

	public CFSecRamSecSysGrpIncTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffSecSysGrpInc ensureRec(ICFSecSecSysGrpInc rec) {
		return (((CFSecBuffSecSysGrpIncFactoryService)(schema.getCFSecBuffFactory().getFactorySecSysGrpInc())).ensureRec(rec));
	}

	@Override
	public ICFSecSecSysGrpInc createSecSysGrpInc( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpInc iBuff )
	{
		final String S_ProcName = "createSecSysGrpInc";
		
		CFSecBuffSecSysGrpInc Buff = (CFSecBuffSecSysGrpInc)ensureRec(iBuff);
		CFSecBuffSecSysGrpIncPKey pkey = (CFSecBuffSecSysGrpIncPKey)(schema.getCFSecBuffFactory().getFactorySecSysGrpInc().newPKey());
		pkey.setRequiredSecSysGrpId(Buff.getRequiredSecSysGrpId());
		pkey.setRequiredInclName(Buff.getRequiredInclName());
		pkey.setRequiredSecSysGrpId( Buff.getRequiredSecSysGrpId() );
		pkey.setRequiredInclName( Buff.getRequiredInclName() );
		Buff.setRequiredContainerGroup( pkey.getRequiredSecSysGrpId() );
		Buff.setRequiredParentSubGroup( pkey.getRequiredInclName() );
		Buff.setRequiredSecSysGrpId( pkey.getRequiredSecSysGrpId() );
		Buff.setRequiredInclName( pkey.getRequiredInclName() );
		CFSecBuffSecSysGrpIncBySysGrpIdxKey keySysGrpIdx = (CFSecBuffSecSysGrpIncBySysGrpIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrpInc().newBySysGrpIdxKey();
		keySysGrpIdx.setRequiredSecSysGrpId( Buff.getRequiredSecSysGrpId() );

		CFSecBuffSecSysGrpIncByNameIdxKey keyNameIdx = (CFSecBuffSecSysGrpIncByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrpInc().newByNameIdxKey();
		keyNameIdx.setRequiredInclName( Buff.getRequiredInclName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		// Validate foreign keys

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableSecSysGrp().readDerivedByIdIdx( Authorization,
						Buff.getRequiredSecSysGrpId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"Container",
						"SecSysGrpIncGroup",
						"SecSysGrpIncGroup",
						"SecSysGrp",
						"SecSysGrp",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFSecBuffSecSysGrpIncPKey, CFSecBuffSecSysGrpInc > subdictSysGrpIdx;
		if( dictBySysGrpIdx.containsKey( keySysGrpIdx ) ) {
			subdictSysGrpIdx = dictBySysGrpIdx.get( keySysGrpIdx );
		}
		else {
			subdictSysGrpIdx = new HashMap< CFSecBuffSecSysGrpIncPKey, CFSecBuffSecSysGrpInc >();
			dictBySysGrpIdx.put( keySysGrpIdx, subdictSysGrpIdx );
		}
		subdictSysGrpIdx.put( pkey, Buff );

		Map< CFSecBuffSecSysGrpIncPKey, CFSecBuffSecSysGrpInc > subdictNameIdx;
		if( dictByNameIdx.containsKey( keyNameIdx ) ) {
			subdictNameIdx = dictByNameIdx.get( keyNameIdx );
		}
		else {
			subdictNameIdx = new HashMap< CFSecBuffSecSysGrpIncPKey, CFSecBuffSecSysGrpInc >();
			dictByNameIdx.put( keyNameIdx, subdictNameIdx );
		}
		subdictNameIdx.put( pkey, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecSysGrpInc.CLASS_CODE) {
				CFSecBuffSecSysGrpInc retbuff = ((CFSecBuffSecSysGrpInc)(schema.getCFSecBuffFactory().getFactorySecSysGrpInc().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecSysGrpInc readDerived( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecSysGrpId,
		String InclName )
	{
		{	$implCommaIJavaOptAtomType$ testSecSysGrpId = SecSysGrpId;
			if (testSecSysGrpId == null) {
				return( null );
			}
		}
		{	$implCommaIJavaOptAtomType$ testInclName = InclName;
			if (testInclName == null) {
				return( null );
			}
		}
		CFSecBuffSecSysGrpIncPKey key = (CFSecBuffSecSysGrpIncPKey)(schema.getCFSecBuffFactory().getFactorySecSysGrpInc().newPKey());
		key.setRequiredSecSysGrpId( SecSysGrpId );
		key.setRequiredInclName( InclName );
		return( readDerived( Authorization, key ) );
	}

	public ICFSecSecSysGrpInc readDerived( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpIncPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecSysGrpInc.readDerived";
		CFSecBuffSecSysGrpIncPKey key = (CFSecBuffSecSysGrpIncPKey)(schema.getCFSecBuffFactory().getFactorySecSysGrpInc().newPKey());
		key.setRequiredSecSysGrpId( PKey.getRequiredSecSysGrpId() );
		key.setRequiredInclName( PKey.getRequiredInclName() );
		ICFSecSecSysGrpInc buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysGrpInc lockDerived( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpIncPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecSysGrpInc.lockDerived";
		CFSecBuffSecSysGrpIncPKey key = (CFSecBuffSecSysGrpIncPKey)(schema.getCFSecBuffFactory().getFactorySecSysGrpInc().newPKey());
		key.setRequiredSecSysGrpId( PKey.getRequiredSecSysGrpId() );
		key.setRequiredInclName( PKey.getRequiredInclName() );
		ICFSecSecSysGrpInc buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysGrpInc[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecSysGrpInc.readAllDerived";
		ICFSecSecSysGrpInc[] retList = new ICFSecSecSysGrpInc[ dictByPKey.values().size() ];
		Iterator< CFSecBuffSecSysGrpInc > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	@Override
	public ICFSecSecSysGrpInc[] readDerivedBySysGrpIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecSysGrpId )
	{
		final String S_ProcName = "CFSecRamSecSysGrpInc.readDerivedBySysGrpIdx";
		CFSecBuffSecSysGrpIncBySysGrpIdxKey key = (CFSecBuffSecSysGrpIncBySysGrpIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrpInc().newBySysGrpIdxKey();

		key.setRequiredSecSysGrpId( SecSysGrpId );
		ICFSecSecSysGrpInc[] recArray;
		if( dictBySysGrpIdx.containsKey( key ) ) {
			Map< CFSecBuffSecSysGrpIncPKey, CFSecBuffSecSysGrpInc > subdictSysGrpIdx
				= dictBySysGrpIdx.get( key );
			recArray = new ICFSecSecSysGrpInc[ subdictSysGrpIdx.size() ];
			Iterator< CFSecBuffSecSysGrpInc > iter = subdictSysGrpIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecBuffSecSysGrpIncPKey, CFSecBuffSecSysGrpInc > subdictSysGrpIdx
				= new HashMap< CFSecBuffSecSysGrpIncPKey, CFSecBuffSecSysGrpInc >();
			dictBySysGrpIdx.put( key, subdictSysGrpIdx );
			recArray = new ICFSecSecSysGrpInc[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecSysGrpInc[] readDerivedByNameIdx( ICFSecAuthorization Authorization,
		String InclName )
	{
		final String S_ProcName = "CFSecRamSecSysGrpInc.readDerivedByNameIdx";
		CFSecBuffSecSysGrpIncByNameIdxKey key = (CFSecBuffSecSysGrpIncByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrpInc().newByNameIdxKey();

		key.setRequiredInclName( InclName );
		ICFSecSecSysGrpInc[] recArray;
		if( dictByNameIdx.containsKey( key ) ) {
			Map< CFSecBuffSecSysGrpIncPKey, CFSecBuffSecSysGrpInc > subdictNameIdx
				= dictByNameIdx.get( key );
			recArray = new ICFSecSecSysGrpInc[ subdictNameIdx.size() ];
			Iterator< CFSecBuffSecSysGrpInc > iter = subdictNameIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecBuffSecSysGrpIncPKey, CFSecBuffSecSysGrpInc > subdictNameIdx
				= new HashMap< CFSecBuffSecSysGrpIncPKey, CFSecBuffSecSysGrpInc >();
			dictByNameIdx.put( key, subdictNameIdx );
			recArray = new ICFSecSecSysGrpInc[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecSysGrpInc readDerivedByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecSysGrpId,
		String InclName )
	{
		final String S_ProcName = "CFSecRamSecSysGrpInc.readDerivedByIdIdx() ";
		CFSecBuffSecSysGrpIncPKey key = (CFSecBuffSecSysGrpIncPKey)(schema.getCFSecBuffFactory().getFactorySecSysGrpInc().newPKey());
		key.setRequiredSecSysGrpId( SecSysGrpId );
		key.setRequiredInclName( InclName );
		ICFSecSecSysGrpInc buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysGrpInc readRec( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecSysGrpId,
		String InclName )
	{
		CFSecBuffSecSysGrpIncPKey key = (CFSecBuffSecSysGrpIncPKey)(schema.getCFSecBuffFactory().getFactorySecSysGrpInc().newPKey());
		key.setRequiredSecSysGrpId( SecSysGrpId );
		key.setRequiredInclName( InclName );
		return( readRec( Authorization, key ) );
	}

	@Override
	public ICFSecSecSysGrpInc readRec( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpIncPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecSysGrpInc.readRec";
		ICFSecSecSysGrpInc buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecSysGrpInc.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysGrpInc lockRec( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpIncPKey PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecSecSysGrpInc buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecSysGrpInc.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysGrpInc[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecSysGrpInc.readAllRec";
		ICFSecSecSysGrpInc buff;
		ArrayList<ICFSecSecSysGrpInc> filteredList = new ArrayList<ICFSecSecSysGrpInc>();
		ICFSecSecSysGrpInc[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSysGrpInc.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecSysGrpInc[0] ) );
	}

	/**
	 *	Read a page of all the specific SecSysGrpInc buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecSysGrpInc instances in the database accessible for the Authorization.
	 */
	@Override
	public ICFSecSecSysGrpInc[] pageAllRec( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 priorSecSysGrpId,
		String priorInclName )
	{
		final String S_ProcName = "pageAllRec";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecSysGrpInc readRecByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecSysGrpId,
		String InclName )
	{
		final String S_ProcName = "CFSecRamSecSysGrpInc.readRecByIdIdx() ";
		ICFSecSecSysGrpInc buff = readDerivedByIdIdx( Authorization,
			SecSysGrpId,
			InclName );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSysGrpInc.CLASS_CODE ) ) {
			return( (ICFSecSecSysGrpInc)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecSysGrpInc[] readRecBySysGrpIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecSysGrpId )
	{
		final String S_ProcName = "CFSecRamSecSysGrpInc.readRecBySysGrpIdx() ";
		ICFSecSecSysGrpInc buff;
		ArrayList<ICFSecSecSysGrpInc> filteredList = new ArrayList<ICFSecSecSysGrpInc>();
		ICFSecSecSysGrpInc[] buffList = readDerivedBySysGrpIdx( Authorization,
			SecSysGrpId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSysGrpInc.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecSysGrpInc)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecSysGrpInc[0] ) );
	}

	@Override
	public ICFSecSecSysGrpInc[] readRecByNameIdx( ICFSecAuthorization Authorization,
		String InclName )
	{
		final String S_ProcName = "CFSecRamSecSysGrpInc.readRecByNameIdx() ";
		ICFSecSecSysGrpInc buff;
		ArrayList<ICFSecSecSysGrpInc> filteredList = new ArrayList<ICFSecSecSysGrpInc>();
		ICFSecSecSysGrpInc[] buffList = readDerivedByNameIdx( Authorization,
			InclName );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSysGrpInc.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecSysGrpInc)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecSysGrpInc[0] ) );
	}

	/**
	 *	Read a page array of the specific SecSysGrpInc buffer instances identified by the duplicate key SysGrpIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecSysGrpId	The SecSysGrpInc key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecSysGrpInc[] pageRecBySysGrpIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecSysGrpId,
		ICFLibKeyHash256 priorSecSysGrpId,
		String priorInclName )
	{
		final String S_ProcName = "pageRecBySysGrpIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecSysGrpInc buffer instances identified by the duplicate key NameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	InclName	The SecSysGrpInc key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecSysGrpInc[] pageRecByNameIdx( ICFSecAuthorization Authorization,
		String InclName,
		ICFLibKeyHash256 priorSecSysGrpId,
		String priorInclName )
	{
		final String S_ProcName = "pageRecByNameIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecSysGrpInc updateSecSysGrpInc( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpInc iBuff )
	{
		CFSecBuffSecSysGrpInc Buff = (CFSecBuffSecSysGrpInc)ensureRec(iBuff);
		CFSecBuffSecSysGrpIncPKey pkey = (CFSecBuffSecSysGrpIncPKey)(schema.getCFSecBuffFactory().getFactorySecSysGrpInc().newPKey());
		pkey = (CFSecBuffSecSysGrpIncPKey)Buff.getPKey();
		CFSecBuffSecSysGrpInc existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecSysGrpInc",
				"Existing record not found",
				"Existing record not found",
				"SecSysGrpInc",
				"SecSysGrpInc",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecSysGrpInc",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecSysGrpIncBySysGrpIdxKey existingKeySysGrpIdx = (CFSecBuffSecSysGrpIncBySysGrpIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrpInc().newBySysGrpIdxKey();
		existingKeySysGrpIdx.setRequiredSecSysGrpId( existing.getRequiredSecSysGrpId() );

		CFSecBuffSecSysGrpIncBySysGrpIdxKey newKeySysGrpIdx = (CFSecBuffSecSysGrpIncBySysGrpIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrpInc().newBySysGrpIdxKey();
		newKeySysGrpIdx.setRequiredSecSysGrpId( Buff.getRequiredSecSysGrpId() );

		CFSecBuffSecSysGrpIncByNameIdxKey existingKeyNameIdx = (CFSecBuffSecSysGrpIncByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrpInc().newByNameIdxKey();
		existingKeyNameIdx.setRequiredInclName( existing.getRequiredInclName() );

		CFSecBuffSecSysGrpIncByNameIdxKey newKeyNameIdx = (CFSecBuffSecSysGrpIncByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrpInc().newByNameIdxKey();
		newKeyNameIdx.setRequiredInclName( Buff.getRequiredInclName() );

		// Check unique indexes

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableSecSysGrp().readDerivedByIdIdx( Authorization,
						Buff.getRequiredSecSysGrpId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateSecSysGrpInc",
						"Container",
						"Container",
						"SecSysGrpIncGroup",
						"SecSysGrpIncGroup",
						"SecSysGrp",
						"SecSysGrp",
						null );
				}
			}
		}

		// Update is valid

		Map< CFSecBuffSecSysGrpIncPKey, CFSecBuffSecSysGrpInc > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		subdict = dictBySysGrpIdx.get( existingKeySysGrpIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictBySysGrpIdx.containsKey( newKeySysGrpIdx ) ) {
			subdict = dictBySysGrpIdx.get( newKeySysGrpIdx );
		}
		else {
			subdict = new HashMap< CFSecBuffSecSysGrpIncPKey, CFSecBuffSecSysGrpInc >();
			dictBySysGrpIdx.put( newKeySysGrpIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByNameIdx.get( existingKeyNameIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByNameIdx.containsKey( newKeyNameIdx ) ) {
			subdict = dictByNameIdx.get( newKeyNameIdx );
		}
		else {
			subdict = new HashMap< CFSecBuffSecSysGrpIncPKey, CFSecBuffSecSysGrpInc >();
			dictByNameIdx.put( newKeyNameIdx, subdict );
		}
		subdict.put( pkey, Buff );

		return(Buff);
	}

	@Override
	public void deleteSecSysGrpInc( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpInc iBuff )
	{
		final String S_ProcName = "CFSecRamSecSysGrpIncTable.deleteSecSysGrpInc() ";
		CFSecBuffSecSysGrpInc Buff = (CFSecBuffSecSysGrpInc)ensureRec(iBuff);
		int classCode;
		CFSecBuffSecSysGrpIncPKey pkey = (CFSecBuffSecSysGrpIncPKey)(Buff.getPKey());
		CFSecBuffSecSysGrpInc existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecSysGrpInc",
				pkey );
		}
		CFSecBuffSecSysGrpIncBySysGrpIdxKey keySysGrpIdx = (CFSecBuffSecSysGrpIncBySysGrpIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrpInc().newBySysGrpIdxKey();
		keySysGrpIdx.setRequiredSecSysGrpId( existing.getRequiredSecSysGrpId() );

		CFSecBuffSecSysGrpIncByNameIdxKey keyNameIdx = (CFSecBuffSecSysGrpIncByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrpInc().newByNameIdxKey();
		keyNameIdx.setRequiredInclName( existing.getRequiredInclName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecBuffSecSysGrpIncPKey, CFSecBuffSecSysGrpInc > subdict;

		dictByPKey.remove( pkey );

		subdict = dictBySysGrpIdx.get( keySysGrpIdx );
		subdict.remove( pkey );

		subdict = dictByNameIdx.get( keyNameIdx );
		subdict.remove( pkey );

	}
	@Override
	public void deleteSecSysGrpIncByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecSysGrpId,
		String InclName )
	{
		CFSecBuffSecSysGrpIncPKey key = (CFSecBuffSecSysGrpIncPKey)(schema.getCFSecBuffFactory().getFactorySecSysGrpInc().newPKey());
		key.setRequiredSecSysGrpId( SecSysGrpId );
		key.setRequiredInclName( InclName );
		deleteSecSysGrpIncByIdIdx( Authorization, key );
	}

	@Override
	public void deleteSecSysGrpIncByIdIdx( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpIncPKey PKey )
	{
		CFSecBuffSecSysGrpIncPKey key = (CFSecBuffSecSysGrpIncPKey)(schema.getCFSecBuffFactory().getFactorySecSysGrpInc().newPKey());
		key.setRequiredSecSysGrpId( PKey.getRequiredSecSysGrpId() );
		key.setRequiredInclName( PKey.getRequiredInclName() );
		CFSecBuffSecSysGrpIncPKey argKey = key;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffSecSysGrpInc cur;
		LinkedList<CFSecBuffSecSysGrpInc> matchSet = new LinkedList<CFSecBuffSecSysGrpInc>();
		Iterator<CFSecBuffSecSysGrpInc> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecSysGrpInc> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecSysGrpInc)(schema.getTableSecSysGrpInc().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSysGrpId(),
				cur.getRequiredInclName() ));
			deleteSecSysGrpInc( Authorization, cur );
		}
	}

	@Override
	public void deleteSecSysGrpIncBySysGrpIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argSecSysGrpId )
	{
		CFSecBuffSecSysGrpIncBySysGrpIdxKey key = (CFSecBuffSecSysGrpIncBySysGrpIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrpInc().newBySysGrpIdxKey();
		key.setRequiredSecSysGrpId( argSecSysGrpId );
		deleteSecSysGrpIncBySysGrpIdx( Authorization, key );
	}

	@Override
	public void deleteSecSysGrpIncBySysGrpIdx( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpIncBySysGrpIdxKey argKey )
	{
		CFSecBuffSecSysGrpInc cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecSysGrpInc> matchSet = new LinkedList<CFSecBuffSecSysGrpInc>();
		Iterator<CFSecBuffSecSysGrpInc> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecSysGrpInc> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecSysGrpInc)(schema.getTableSecSysGrpInc().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSysGrpId(),
				cur.getRequiredInclName() ));
			deleteSecSysGrpInc( Authorization, cur );
		}
	}

	@Override
	public void deleteSecSysGrpIncByNameIdx( ICFSecAuthorization Authorization,
		String argInclName )
	{
		CFSecBuffSecSysGrpIncByNameIdxKey key = (CFSecBuffSecSysGrpIncByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrpInc().newByNameIdxKey();
		key.setRequiredInclName( argInclName );
		deleteSecSysGrpIncByNameIdx( Authorization, key );
	}

	@Override
	public void deleteSecSysGrpIncByNameIdx( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpIncByNameIdxKey argKey )
	{
		CFSecBuffSecSysGrpInc cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecSysGrpInc> matchSet = new LinkedList<CFSecBuffSecSysGrpInc>();
		Iterator<CFSecBuffSecSysGrpInc> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecSysGrpInc> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecSysGrpInc)(schema.getTableSecSysGrpInc().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSysGrpId(),
				cur.getRequiredInclName() ));
			deleteSecSysGrpInc( Authorization, cur );
		}
	}
}

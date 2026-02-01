
// Description: Java 25 in-memory RAM DbIO implementation for ISOTZone.

/*
 *	io.github.msobkow.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	This file is part of Mark's Code Fractal CFSec.
 *	
 *	Mark's Code Fractal CFSec is available under dual commercial license from
 *	Mark Stephen Sobkow, or under the terms of the GNU Library General Public License,
 *	Version 3 or later.
 *	
 *	Mark's Code Fractal CFSec is free software: you can redistribute it and/or
 *	modify it under the terms of the GNU Library General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *	
 *	Mark's Code Fractal CFSec is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU Library General Public License
 *	along with Mark's Code Fractal CFSec.  If not, see <https://www.gnu.org/licenses/>.
 *	
 *	If you wish to modify and use this code without publishing your changes in order to
 *	tie it to proprietary code, please contact Mark Stephen Sobkow
 *	for a commercial license at mark.sobkow@gmail.com
 *	
 */

package io.github.msobkow.v3_1.cfsec.cfsecram;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.time.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import io.github.msobkow.v3_1.cflib.*;
import io.github.msobkow.v3_1.cflib.dbutil.*;

import io.github.msobkow.v3_1.cfsec.cfsec.*;
import io.github.msobkow.v3_1.cfsec.cfsec.buff.*;
import io.github.msobkow.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamISOTZoneTable in-memory RAM DbIO implementation
 *	for ISOTZone.
 */
public class CFSecRamISOTZoneTable
	implements ICFSecISOTZoneTable
{
	private ICFSecSchema schema;
	private Map< Short,
				CFSecBuffISOTZone > dictByPKey
		= new HashMap< Short,
				CFSecBuffISOTZone >();
	private Map< CFSecBuffISOTZoneByOffsetIdxKey,
				Map< Short,
					CFSecBuffISOTZone >> dictByOffsetIdx
		= new HashMap< CFSecBuffISOTZoneByOffsetIdxKey,
				Map< Short,
					CFSecBuffISOTZone >>();
	private Map< CFSecBuffISOTZoneByUTZNameIdxKey,
			CFSecBuffISOTZone > dictByUTZNameIdx
		= new HashMap< CFSecBuffISOTZoneByUTZNameIdxKey,
			CFSecBuffISOTZone >();
	private Map< CFSecBuffISOTZoneByIso8601IdxKey,
				Map< Short,
					CFSecBuffISOTZone >> dictByIso8601Idx
		= new HashMap< CFSecBuffISOTZoneByIso8601IdxKey,
				Map< Short,
					CFSecBuffISOTZone >>();

	public CFSecRamISOTZoneTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffISOTZone ensureRec(ICFSecISOTZone rec) {
		if (rec == null) {
			return( null );
		}
		else {
			int classCode = rec.getClassCode();
			if (classCode == ICFSecISOTZone.CLASS_CODE) {
				return( ((CFSecBuffISOTZoneDefaultFactory)(schema.getFactoryISOTZone())).ensureRec((ICFSecISOTZone)rec) );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), "ensureRec", "rec", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecISOTZone createISOTZone( ICFSecAuthorization Authorization,
		ICFSecISOTZone iBuff )
	{
		final String S_ProcName = "createISOTZone";
		
		CFSecBuffISOTZone Buff = (CFSecBuffISOTZone)ensureRec(iBuff);
		Short pkey;
		pkey = schema.nextISOTZoneIdGen();
		Buff.setRequiredISOTZoneId( pkey );
		CFSecBuffISOTZoneByOffsetIdxKey keyOffsetIdx = (CFSecBuffISOTZoneByOffsetIdxKey)schema.getFactoryISOTZone().newByOffsetIdxKey();
		keyOffsetIdx.setRequiredTZHourOffset( Buff.getRequiredTZHourOffset() );
		keyOffsetIdx.setRequiredTZMinOffset( Buff.getRequiredTZMinOffset() );

		CFSecBuffISOTZoneByUTZNameIdxKey keyUTZNameIdx = (CFSecBuffISOTZoneByUTZNameIdxKey)schema.getFactoryISOTZone().newByUTZNameIdxKey();
		keyUTZNameIdx.setRequiredTZName( Buff.getRequiredTZName() );

		CFSecBuffISOTZoneByIso8601IdxKey keyIso8601Idx = (CFSecBuffISOTZoneByIso8601IdxKey)schema.getFactoryISOTZone().newByIso8601IdxKey();
		keyIso8601Idx.setRequiredIso8601( Buff.getRequiredIso8601() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUTZNameIdx.containsKey( keyUTZNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"ISOTZoneUTZNameIdx",
				"ISOTZoneUTZNameIdx",
				keyUTZNameIdx );
		}

		// Validate foreign keys

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< Short, CFSecBuffISOTZone > subdictOffsetIdx;
		if( dictByOffsetIdx.containsKey( keyOffsetIdx ) ) {
			subdictOffsetIdx = dictByOffsetIdx.get( keyOffsetIdx );
		}
		else {
			subdictOffsetIdx = new HashMap< Short, CFSecBuffISOTZone >();
			dictByOffsetIdx.put( keyOffsetIdx, subdictOffsetIdx );
		}
		subdictOffsetIdx.put( pkey, Buff );

		dictByUTZNameIdx.put( keyUTZNameIdx, Buff );

		Map< Short, CFSecBuffISOTZone > subdictIso8601Idx;
		if( dictByIso8601Idx.containsKey( keyIso8601Idx ) ) {
			subdictIso8601Idx = dictByIso8601Idx.get( keyIso8601Idx );
		}
		else {
			subdictIso8601Idx = new HashMap< Short, CFSecBuffISOTZone >();
			dictByIso8601Idx.put( keyIso8601Idx, subdictIso8601Idx );
		}
		subdictIso8601Idx.put( pkey, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecISOTZone.CLASS_CODE) {
				CFSecBuffISOTZone retbuff = ((CFSecBuffISOTZone)(schema.getFactoryISOTZone().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecISOTZone readDerived( ICFSecAuthorization Authorization,
		Short PKey )
	{
		final String S_ProcName = "CFSecRamISOTZone.readDerived";
		ICFSecISOTZone buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecISOTZone lockDerived( ICFSecAuthorization Authorization,
		Short PKey )
	{
		final String S_ProcName = "CFSecRamISOTZone.lockDerived";
		ICFSecISOTZone buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecISOTZone[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamISOTZone.readAllDerived";
		ICFSecISOTZone[] retList = new ICFSecISOTZone[ dictByPKey.values().size() ];
		Iterator< CFSecBuffISOTZone > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	@Override
	public ICFSecISOTZone[] readDerivedByOffsetIdx( ICFSecAuthorization Authorization,
		short TZHourOffset,
		short TZMinOffset )
	{
		final String S_ProcName = "CFSecRamISOTZone.readDerivedByOffsetIdx";
		CFSecBuffISOTZoneByOffsetIdxKey key = (CFSecBuffISOTZoneByOffsetIdxKey)schema.getFactoryISOTZone().newByOffsetIdxKey();

		key.setRequiredTZHourOffset( TZHourOffset );
		key.setRequiredTZMinOffset( TZMinOffset );
		ICFSecISOTZone[] recArray;
		if( dictByOffsetIdx.containsKey( key ) ) {
			Map< Short, CFSecBuffISOTZone > subdictOffsetIdx
				= dictByOffsetIdx.get( key );
			recArray = new ICFSecISOTZone[ subdictOffsetIdx.size() ];
			Iterator< CFSecBuffISOTZone > iter = subdictOffsetIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< Short, CFSecBuffISOTZone > subdictOffsetIdx
				= new HashMap< Short, CFSecBuffISOTZone >();
			dictByOffsetIdx.put( key, subdictOffsetIdx );
			recArray = new ICFSecISOTZone[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecISOTZone readDerivedByUTZNameIdx( ICFSecAuthorization Authorization,
		String TZName )
	{
		final String S_ProcName = "CFSecRamISOTZone.readDerivedByUTZNameIdx";
		CFSecBuffISOTZoneByUTZNameIdxKey key = (CFSecBuffISOTZoneByUTZNameIdxKey)schema.getFactoryISOTZone().newByUTZNameIdxKey();

		key.setRequiredTZName( TZName );
		ICFSecISOTZone buff;
		if( dictByUTZNameIdx.containsKey( key ) ) {
			buff = dictByUTZNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecISOTZone[] readDerivedByIso8601Idx( ICFSecAuthorization Authorization,
		String Iso8601 )
	{
		final String S_ProcName = "CFSecRamISOTZone.readDerivedByIso8601Idx";
		CFSecBuffISOTZoneByIso8601IdxKey key = (CFSecBuffISOTZoneByIso8601IdxKey)schema.getFactoryISOTZone().newByIso8601IdxKey();

		key.setRequiredIso8601( Iso8601 );
		ICFSecISOTZone[] recArray;
		if( dictByIso8601Idx.containsKey( key ) ) {
			Map< Short, CFSecBuffISOTZone > subdictIso8601Idx
				= dictByIso8601Idx.get( key );
			recArray = new ICFSecISOTZone[ subdictIso8601Idx.size() ];
			Iterator< CFSecBuffISOTZone > iter = subdictIso8601Idx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< Short, CFSecBuffISOTZone > subdictIso8601Idx
				= new HashMap< Short, CFSecBuffISOTZone >();
			dictByIso8601Idx.put( key, subdictIso8601Idx );
			recArray = new ICFSecISOTZone[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecISOTZone readDerivedByIdIdx( ICFSecAuthorization Authorization,
		short ISOTZoneId )
	{
		final String S_ProcName = "CFSecRamISOTZone.readDerivedByIdIdx() ";
		ICFSecISOTZone buff;
		if( dictByPKey.containsKey( ISOTZoneId ) ) {
			buff = dictByPKey.get( ISOTZoneId );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecISOTZone readRec( ICFSecAuthorization Authorization,
		Short PKey )
	{
		final String S_ProcName = "CFSecRamISOTZone.readRec";
		ICFSecISOTZone buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecISOTZone.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecISOTZone lockRec( ICFSecAuthorization Authorization,
		Short PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecISOTZone buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecISOTZone.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecISOTZone[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamISOTZone.readAllRec";
		ICFSecISOTZone buff;
		ArrayList<ICFSecISOTZone> filteredList = new ArrayList<ICFSecISOTZone>();
		ICFSecISOTZone[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecISOTZone.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecISOTZone[0] ) );
	}

	@Override
	public ICFSecISOTZone readRecByIdIdx( ICFSecAuthorization Authorization,
		short ISOTZoneId )
	{
		final String S_ProcName = "CFSecRamISOTZone.readRecByIdIdx() ";
		ICFSecISOTZone buff = readDerivedByIdIdx( Authorization,
			ISOTZoneId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecISOTZone.CLASS_CODE ) ) {
			return( (ICFSecISOTZone)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecISOTZone[] readRecByOffsetIdx( ICFSecAuthorization Authorization,
		short TZHourOffset,
		short TZMinOffset )
	{
		final String S_ProcName = "CFSecRamISOTZone.readRecByOffsetIdx() ";
		ICFSecISOTZone buff;
		ArrayList<ICFSecISOTZone> filteredList = new ArrayList<ICFSecISOTZone>();
		ICFSecISOTZone[] buffList = readDerivedByOffsetIdx( Authorization,
			TZHourOffset,
			TZMinOffset );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecISOTZone.CLASS_CODE ) ) {
				filteredList.add( (ICFSecISOTZone)buff );
			}
		}
		return( filteredList.toArray( new ICFSecISOTZone[0] ) );
	}

	@Override
	public ICFSecISOTZone readRecByUTZNameIdx( ICFSecAuthorization Authorization,
		String TZName )
	{
		final String S_ProcName = "CFSecRamISOTZone.readRecByUTZNameIdx() ";
		ICFSecISOTZone buff = readDerivedByUTZNameIdx( Authorization,
			TZName );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecISOTZone.CLASS_CODE ) ) {
			return( (ICFSecISOTZone)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecISOTZone[] readRecByIso8601Idx( ICFSecAuthorization Authorization,
		String Iso8601 )
	{
		final String S_ProcName = "CFSecRamISOTZone.readRecByIso8601Idx() ";
		ICFSecISOTZone buff;
		ArrayList<ICFSecISOTZone> filteredList = new ArrayList<ICFSecISOTZone>();
		ICFSecISOTZone[] buffList = readDerivedByIso8601Idx( Authorization,
			Iso8601 );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecISOTZone.CLASS_CODE ) ) {
				filteredList.add( (ICFSecISOTZone)buff );
			}
		}
		return( filteredList.toArray( new ICFSecISOTZone[0] ) );
	}

	public ICFSecISOTZone updateISOTZone( ICFSecAuthorization Authorization,
		ICFSecISOTZone iBuff )
	{
		CFSecBuffISOTZone Buff = (CFSecBuffISOTZone)ensureRec(iBuff);
		Short pkey = Buff.getPKey();
		CFSecBuffISOTZone existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateISOTZone",
				"Existing record not found",
				"Existing record not found",
				"ISOTZone",
				"ISOTZone",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateISOTZone",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffISOTZoneByOffsetIdxKey existingKeyOffsetIdx = (CFSecBuffISOTZoneByOffsetIdxKey)schema.getFactoryISOTZone().newByOffsetIdxKey();
		existingKeyOffsetIdx.setRequiredTZHourOffset( existing.getRequiredTZHourOffset() );
		existingKeyOffsetIdx.setRequiredTZMinOffset( existing.getRequiredTZMinOffset() );

		CFSecBuffISOTZoneByOffsetIdxKey newKeyOffsetIdx = (CFSecBuffISOTZoneByOffsetIdxKey)schema.getFactoryISOTZone().newByOffsetIdxKey();
		newKeyOffsetIdx.setRequiredTZHourOffset( Buff.getRequiredTZHourOffset() );
		newKeyOffsetIdx.setRequiredTZMinOffset( Buff.getRequiredTZMinOffset() );

		CFSecBuffISOTZoneByUTZNameIdxKey existingKeyUTZNameIdx = (CFSecBuffISOTZoneByUTZNameIdxKey)schema.getFactoryISOTZone().newByUTZNameIdxKey();
		existingKeyUTZNameIdx.setRequiredTZName( existing.getRequiredTZName() );

		CFSecBuffISOTZoneByUTZNameIdxKey newKeyUTZNameIdx = (CFSecBuffISOTZoneByUTZNameIdxKey)schema.getFactoryISOTZone().newByUTZNameIdxKey();
		newKeyUTZNameIdx.setRequiredTZName( Buff.getRequiredTZName() );

		CFSecBuffISOTZoneByIso8601IdxKey existingKeyIso8601Idx = (CFSecBuffISOTZoneByIso8601IdxKey)schema.getFactoryISOTZone().newByIso8601IdxKey();
		existingKeyIso8601Idx.setRequiredIso8601( existing.getRequiredIso8601() );

		CFSecBuffISOTZoneByIso8601IdxKey newKeyIso8601Idx = (CFSecBuffISOTZoneByIso8601IdxKey)schema.getFactoryISOTZone().newByIso8601IdxKey();
		newKeyIso8601Idx.setRequiredIso8601( Buff.getRequiredIso8601() );

		// Check unique indexes

		if( ! existingKeyUTZNameIdx.equals( newKeyUTZNameIdx ) ) {
			if( dictByUTZNameIdx.containsKey( newKeyUTZNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateISOTZone",
					"ISOTZoneUTZNameIdx",
					"ISOTZoneUTZNameIdx",
					newKeyUTZNameIdx );
			}
		}

		// Validate foreign keys

		// Update is valid

		Map< Short, CFSecBuffISOTZone > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		subdict = dictByOffsetIdx.get( existingKeyOffsetIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByOffsetIdx.containsKey( newKeyOffsetIdx ) ) {
			subdict = dictByOffsetIdx.get( newKeyOffsetIdx );
		}
		else {
			subdict = new HashMap< Short, CFSecBuffISOTZone >();
			dictByOffsetIdx.put( newKeyOffsetIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByUTZNameIdx.remove( existingKeyUTZNameIdx );
		dictByUTZNameIdx.put( newKeyUTZNameIdx, Buff );

		subdict = dictByIso8601Idx.get( existingKeyIso8601Idx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByIso8601Idx.containsKey( newKeyIso8601Idx ) ) {
			subdict = dictByIso8601Idx.get( newKeyIso8601Idx );
		}
		else {
			subdict = new HashMap< Short, CFSecBuffISOTZone >();
			dictByIso8601Idx.put( newKeyIso8601Idx, subdict );
		}
		subdict.put( pkey, Buff );

		return(Buff);
	}

	@Override
	public void deleteISOTZone( ICFSecAuthorization Authorization,
		ICFSecISOTZone iBuff )
	{
		final String S_ProcName = "CFSecRamISOTZoneTable.deleteISOTZone() ";
		CFSecBuffISOTZone Buff = (CFSecBuffISOTZone)ensureRec(iBuff);
		int classCode;
		Short pkey = (Short)(Buff.getPKey());
		CFSecBuffISOTZone existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteISOTZone",
				pkey );
		}
		CFSecBuffISOTZoneByOffsetIdxKey keyOffsetIdx = (CFSecBuffISOTZoneByOffsetIdxKey)schema.getFactoryISOTZone().newByOffsetIdxKey();
		keyOffsetIdx.setRequiredTZHourOffset( existing.getRequiredTZHourOffset() );
		keyOffsetIdx.setRequiredTZMinOffset( existing.getRequiredTZMinOffset() );

		CFSecBuffISOTZoneByUTZNameIdxKey keyUTZNameIdx = (CFSecBuffISOTZoneByUTZNameIdxKey)schema.getFactoryISOTZone().newByUTZNameIdxKey();
		keyUTZNameIdx.setRequiredTZName( existing.getRequiredTZName() );

		CFSecBuffISOTZoneByIso8601IdxKey keyIso8601Idx = (CFSecBuffISOTZoneByIso8601IdxKey)schema.getFactoryISOTZone().newByIso8601IdxKey();
		keyIso8601Idx.setRequiredIso8601( existing.getRequiredIso8601() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< Short, CFSecBuffISOTZone > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByOffsetIdx.get( keyOffsetIdx );
		subdict.remove( pkey );

		dictByUTZNameIdx.remove( keyUTZNameIdx );

		subdict = dictByIso8601Idx.get( keyIso8601Idx );
		subdict.remove( pkey );

	}
	@Override
	public void deleteISOTZoneByIdIdx( ICFSecAuthorization Authorization,
		Short argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffISOTZone cur;
		LinkedList<CFSecBuffISOTZone> matchSet = new LinkedList<CFSecBuffISOTZone>();
		Iterator<CFSecBuffISOTZone> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffISOTZone> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffISOTZone)(schema.getTableISOTZone().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOTZoneId() ));
			deleteISOTZone( Authorization, cur );
		}
	}

	@Override
	public void deleteISOTZoneByOffsetIdx( ICFSecAuthorization Authorization,
		short argTZHourOffset,
		short argTZMinOffset )
	{
		CFSecBuffISOTZoneByOffsetIdxKey key = (CFSecBuffISOTZoneByOffsetIdxKey)schema.getFactoryISOTZone().newByOffsetIdxKey();
		key.setRequiredTZHourOffset( argTZHourOffset );
		key.setRequiredTZMinOffset( argTZMinOffset );
		deleteISOTZoneByOffsetIdx( Authorization, key );
	}

	@Override
	public void deleteISOTZoneByOffsetIdx( ICFSecAuthorization Authorization,
		ICFSecISOTZoneByOffsetIdxKey argKey )
	{
		CFSecBuffISOTZone cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffISOTZone> matchSet = new LinkedList<CFSecBuffISOTZone>();
		Iterator<CFSecBuffISOTZone> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffISOTZone> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffISOTZone)(schema.getTableISOTZone().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOTZoneId() ));
			deleteISOTZone( Authorization, cur );
		}
	}

	@Override
	public void deleteISOTZoneByUTZNameIdx( ICFSecAuthorization Authorization,
		String argTZName )
	{
		CFSecBuffISOTZoneByUTZNameIdxKey key = (CFSecBuffISOTZoneByUTZNameIdxKey)schema.getFactoryISOTZone().newByUTZNameIdxKey();
		key.setRequiredTZName( argTZName );
		deleteISOTZoneByUTZNameIdx( Authorization, key );
	}

	@Override
	public void deleteISOTZoneByUTZNameIdx( ICFSecAuthorization Authorization,
		ICFSecISOTZoneByUTZNameIdxKey argKey )
	{
		CFSecBuffISOTZone cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffISOTZone> matchSet = new LinkedList<CFSecBuffISOTZone>();
		Iterator<CFSecBuffISOTZone> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffISOTZone> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffISOTZone)(schema.getTableISOTZone().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOTZoneId() ));
			deleteISOTZone( Authorization, cur );
		}
	}

	@Override
	public void deleteISOTZoneByIso8601Idx( ICFSecAuthorization Authorization,
		String argIso8601 )
	{
		CFSecBuffISOTZoneByIso8601IdxKey key = (CFSecBuffISOTZoneByIso8601IdxKey)schema.getFactoryISOTZone().newByIso8601IdxKey();
		key.setRequiredIso8601( argIso8601 );
		deleteISOTZoneByIso8601Idx( Authorization, key );
	}

	@Override
	public void deleteISOTZoneByIso8601Idx( ICFSecAuthorization Authorization,
		ICFSecISOTZoneByIso8601IdxKey argKey )
	{
		CFSecBuffISOTZone cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffISOTZone> matchSet = new LinkedList<CFSecBuffISOTZone>();
		Iterator<CFSecBuffISOTZone> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffISOTZone> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffISOTZone)(schema.getTableISOTZone().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOTZoneId() ));
			deleteISOTZone( Authorization, cur );
		}
	}
}
